# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail list-packs --json`` and ``guardrail use-pack``.

use-pack writes ``guardrail[.connectors.C].rule_pack`` through the config
writer; the writer is recorded here, not run.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from unittest.mock import MagicMock

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import config as config_mod
from defenseclaw import config_writer, policy_catalog, rulepack_validation
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import (
    ApplicationProtectionConnectorConfig,
    CustomRulePack,
    GuardrailProfile,
    GuardrailRulesConfig,
    PerConnectorGuardrailConfig,
    default_config,
)
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env
from tests.helpers import select_pack

# The real writer, before a fixture swaps in a recorder.
_REAL_APPLY = config_writer.apply


def _valid(path, **_kwargs):
    return rulepack_validation.RulePackValidationResult(
        wire_version=1, kind="validation_result", valid=True, summary={"rule_count": 1, "digest": "c" * 64, "files_digest": "a" * 64}
    )


def _invalid(path, **_kwargs):
    return rulepack_validation.RulePackValidationResult(
        wire_version=1,
        kind="validation_error",
        valid=False,
        error=rulepack_validation.RulePackValidationIssue(path="$.rules", code="bad_rule", reason="broken"),
    )


def _unavailable(path, **_kwargs):
    raise rulepack_validation.RulePackValidationBridgeError("no gateway binary", code="gateway_unavailable")


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _valid)
    guardrail_root = tmp_path / "dc" / "policies" / "guardrail"
    for preset in ("default", "strict", "permissive"):
        (guardrail_root / preset / "rules").mkdir(parents=True)
    custom = tmp_path / "packs" / "team"
    (custom / "rules").mkdir(parents=True)

    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.enabled = True
    cfg.guardrail.mode = "action"
    cfg.guardrail.port = 4321
    cfg.guardrail.rule_pack = "default"
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    writes: list[list[config_writer.Change]] = []

    def _apply(changes, actor, reason, expect_sha256=None, **_kwargs):
        writes.append(list(changes))
        return config_writer.WriteResult(generation=7, sha256="0" * 64)

    monkeypatch.setattr(config_writer, "apply", _apply)
    return app, guardrail_root, custom, writes


def _run(app, args):
    return CliRunner().invoke(cmd_guardrail.guardrail, args, obj=app, catch_exceptions=False)


def _json_strings(value):
    """Every string in a decoded JSON document, as a reader sees it."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)


def _persist(app) -> None:
    """Save the in-memory config as config.yaml: --repin reads its pins from the file."""
    path = config_mod.config_path_for_data_dir(app.cfg.data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    saved = config_mod._config_to_dict(app.cfg)
    keep = ("config_version", "data_dir", "policy_dir", "claw", "guardrail", "application_protection")
    path.write_text(yaml.safe_dump({key: saved[key] for key in keep if key in saved}))


def _multi(app, overrides: dict[str, str]):
    app.cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig() for name in overrides}
    for name, path in overrides.items():
        select_pack(app.cfg, app.cfg.guardrail.connectors[name], path)


def test_global_switch_clears_overrides_and_reports_them(env):
    app, root, custom, writes = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["scope"] == "global"
    assert payload["connector"] is None
    assert payload["pack"] == "strict"
    assert payload["path"] == str(root / "strict")
    assert payload["cleared_overrides"] == ["codex"]
    assert payload["validation"]["valid"] is True
    assert len(writes) == 1
    assert not any(c.path.startswith("guardrail.connectors.claudecode") for c in writes[0])


def test_connector_scope_leaves_peers_alone(env):
    app, root, custom, writes = env
    _multi(app, {"codex": "", "claudecode": str(root / "permissive")})
    result = _run(app, ["use-pack", "team", "--connector", "codex", "--json"])
    # "team" isn't under <policy_dir>/guardrail, so it is not a known name.
    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False
    assert writes == []

    result = _run(app, ["use-pack", str(custom), "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert (payload["scope"], payload["connector"], payload["cleared_overrides"]) == ("connector", "codex", [])
    paths = [c.path for c in writes[-1]]
    assert paths == [
        "guardrail.custom_packs.team",
        "guardrail.connectors.codex.rule_pack",
    ]


def test_connector_custom_path_cannot_replace_global_pack(env, tmp_path):
    app, _root, custom, writes = env
    app.cfg.guardrail.rule_pack = "team"
    app.cfg.guardrail.custom_packs = {
        "team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)
    }
    other = tmp_path / "another" / "team"
    (other / "rules").mkdir(parents=True)

    result = _run(app, ["use-pack", str(other), "--connector", "codex", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.output)["ok"] is False
    assert app.cfg.guardrail.custom_packs["team"].path == str(custom)
    assert writes == []


def test_registered_custom_pack_key_is_selected_by_name(env):
    """GAP-0049: a guardrail.custom_packs key selects like config set guardrail.rule_pack does,
    keeping its pinned digest; a pack edited since it was pinned is refused."""
    app, _root, custom, writes = env
    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)}
    result = _run(app, ["use-pack", "team", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["pack"] == "team"
    assert writes[-1] == [config_writer.Change("guardrail.rule_pack", "team")]

    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    refused = _run(app, ["use-pack", "team"])
    assert refused.exit_code == 1
    assert "config set guardrail.custom_packs.team.digest sha256:" + "a" * 64 in refused.output
    assert len(writes) == 1

    # GAP-0159: an unknown name lists the registered custom_packs names it could have been.
    unknown = _run(app, ["use-pack", "nosuch"])
    assert unknown.exit_code == 1 and "guardrail.custom_packs name (team)" in unknown.output


@pytest.mark.parametrize("by_name", [False, True], ids=["path", "name"])
def test_stale_pin_is_replaced_only_by_a_confirmed_repin(env, monkeypatch, by_name):
    """W4 review: plain use-pack never replaces a stale pin; --repin shows both digests and asks."""
    app, _root, custom, writes = env
    app.cfg.guardrail.rule_pack = "team"
    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    pack = "team" if by_name else str(custom)
    repinned = config_writer.Change("guardrail.custom_packs.team", {"path": str(custom), "digest": "sha256:" + "a" * 64})

    for args in (["--json"], []):
        refused = _run(app, ["use-pack", pack, *args])
        assert refused.exit_code == 1 and writes == [], refused.output
        assert "sha256:" + "b" * 64 in refused.output and "sha256:" + "a" * 64 in refused.output
        # JSON escapes the backslashes of a Windows path: read its values.
        text = " ".join(_json_strings(json.loads(refused.output))) if args else refused.output
        assert f"use-pack {pack} --repin" in text

    _persist(app)
    unattended = _run(app, ["use-pack", pack, "--repin", "--json"])
    assert unattended.exit_code == 2 and writes == [], unattended.output
    assert "--yes" in json.loads(unattended.output)["message"]

    declined = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", pack, "--repin"], obj=app, input="n\n")
    assert declined.exit_code == 1 and writes == [], declined.output
    assert "sha256:" + "b" * 64 in declined.output and "sha256:" + "a" * 64 in declined.output

    confirmed = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", pack, "--repin"], obj=app, input="y\n")
    assert confirmed.exit_code == 0, confirmed.output
    assert repinned in writes[-1] and "Re-pinned 'team'" in confirmed.output
    writes.clear()

    scripted = _run(app, ["use-pack", pack, "--repin", "--yes", "--json"])
    assert scripted.exit_code == 0, scripted.output
    assert repinned in writes[-1] and "Re-pinned" in json.loads(scripted.output)["message"]
    writes.clear()

    # --repin never pins content that does not validate.
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _invalid)
    assert _run(app, ["use-pack", pack, "--repin", "--yes", "--json"]).exit_code == 1 and writes == []
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _unavailable)
    assert _run(app, ["use-pack", pack, "--repin", "--yes", "--json"]).exit_code == 2 and writes == []


@pytest.mark.parametrize(
    ("args", "setup", "named"),
    [
        (["--connector", "codex"], "peer", "Claude Code"),
        (["--connector", "codex"], "global", "the global pack"),
        (["--connector", "codex"], "profile", "profile engineering"),
        (["--connector", "codex"], "profile_connector", "Codex in profile engineering"),
        ([], "profile_connector", "Codex in profile engineering"),
    ],
)
def test_repin_names_every_other_scope_that_shares_the_pin(env, args, setup, named):
    """W4 review round 3: the digest pin is one custom_packs key, so a scoped
    --repin changes every scope that selects it; the prompt and the result name them."""
    app, _root, custom, writes = env
    gc = app.cfg.guardrail
    gc.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    gc.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="team")}
    if setup == "peer":
        gc.connectors["claudecode"] = PerConnectorGuardrailConfig(rule_pack="team")
    elif setup == "global":
        gc.rule_pack = "team"
    elif setup == "profile":
        gc.profiles = {"engineering": GuardrailProfile(rule_pack="team")}
    else:
        gc.profiles = {
            "engineering": GuardrailProfile(connectors={"codex": PerConnectorGuardrailConfig(rule_pack="team")})
        }
    _persist(app)
    note = f"The pin is shared, so the edited pack also applies to {named}"

    unattended = _run(app, ["use-pack", "team", *args, "--repin", "--json"])
    assert unattended.exit_code == 2 and writes == [], unattended.output
    assert note in json.loads(unattended.output)["message"]

    declined = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", "team", *args, "--repin"], obj=app, input="n\n")
    assert declined.exit_code == 1 and writes == [], declined.output
    assert note in " ".join(declined.output.split())

    scripted = _run(app, ["use-pack", "team", *args, "--repin", "--yes", "--json"])
    assert scripted.exit_code == 0, scripted.output
    assert note in json.loads(scripted.output)["message"]
    assert "repin_shared=" in app.logger.log_config_change.call_args.args[-1]


def test_repin_of_a_pin_no_other_scope_uses_names_no_one_else(env):
    app, _root, custom, _writes = env
    gc = app.cfg.guardrail
    gc.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    gc.connectors = {
        "codex": PerConnectorGuardrailConfig(rule_pack="team"),
        "claudecode": PerConnectorGuardrailConfig(rule_pack="strict"),
    }
    _persist(app)
    for args in (["--connector", "codex"], []):
        result = _run(app, ["use-pack", "team", *args, "--repin", "--yes", "--json"])
        assert result.exit_code == 0, result.output
        assert "shared" not in json.loads(result.output)["message"]


@pytest.fixture
def on_disk(env, monkeypatch):
    """*env* with config.yaml on disk (Codex selects the stale team pin) and a
    writer that, like config_writer, refuses a stale ``expect_sha256``."""
    app, _root, custom, writes = env
    path = config_mod.config_path_for_data_dir(app.cfg.data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "config_version": config_mod.CURRENT_CONFIG_VERSION,
        "data_dir": app.cfg.data_dir,
        "policy_dir": app.cfg.policy_dir,
        "claw": {"mode": "codex"},
        "guardrail": {
            "enabled": True,
            "connector": "codex",
            "mode": "action",
            "port": 4321,
            "rule_pack": "default",
            "custom_packs": {"team": {"path": str(custom), "digest": "sha256:" + "b" * 64}},
            "connectors": {"codex": {"rule_pack": "team"}, "claudecode": {"rule_pack": "strict"}},
        },
    }
    path.write_text(yaml.safe_dump(doc))
    # The config the command started with: the same file.
    app.cfg = config_mod.load(parsed_source=yaml.safe_load(path.read_text()))
    conflicts: list[str] = []

    def _apply(changes, actor, reason, expect_sha256=None, path=None, **_kwargs):
        target = pathlib.Path(path)
        current = hashlib.sha256(target.read_bytes() if target.exists() else b"").hexdigest()
        if expect_sha256 is not None and expect_sha256 != current:
            conflicts.append(reason)
            raise config_writer.ConfigConflictError("config.yaml changed since it was read")
        writes.append(list(changes))
        return config_writer.WriteResult(generation=7, sha256=current)

    monkeypatch.setattr(config_writer, "apply", _apply)

    def edit(profile: str = "", **connectors):
        """Another writer (or a hand edit) selects packs while use-pack waits."""
        doc["guardrail"]["connectors"].update({name: {"rule_pack": pack} for name, pack in connectors.items()})
        if profile:
            doc["guardrail"]["profiles"] = {profile: {"rule_pack": "team"}}
        path.write_text(yaml.safe_dump(doc))

    return app, writes, conflicts, edit, doc, path


def _confirm_after(edits: list, asked: list):
    """A confirm prompt that runs the next queued edit while it waits."""

    def _confirm():
        asked.append(True)
        if edits:
            edits.pop(0)()
        return True

    return _confirm


def test_repin_reads_the_config_on_disk_not_the_one_loaded_at_start(on_disk):
    """config.yaml changed between the command's start and the re-pin."""
    app, writes, conflicts, edit, _doc, _path = on_disk
    edit(claudecode="team")
    result = _run(app, ["use-pack", "team", "--connector", "codex", "--repin", "--yes", "--json"])
    assert result.exit_code == 0, result.output
    assert conflicts == [] and len(writes) == 1
    assert "also applies to Claude Code" in json.loads(result.output)["message"]


def _peer_selects_pin(doc, path):
    doc["guardrail"]["connectors"]["claudecode"] = {"rule_pack": "team"}
    path.write_text(yaml.safe_dump(doc))


def _profile_selects_pin(doc, path):
    doc["guardrail"]["profiles"] = {"engineering": {"rule_pack": "team"}}
    path.write_text(yaml.safe_dump(doc))


def _pin_refreshed(doc, path):
    doc["guardrail"]["custom_packs"]["team"]["digest"] = "sha256:" + "a" * 64
    path.write_text(yaml.safe_dump(doc))


def _gone(_doc, path: pathlib.Path) -> None:
    path.unlink()


def _emptied(_doc, path: pathlib.Path) -> None:
    path.write_bytes(b"")


def _replaced(doc, path: pathlib.Path) -> None:
    """Removed, then another config.yaml put in its place."""
    path.unlink()
    path.write_text(yaml.safe_dump({**doc, "guardrail": {**doc["guardrail"], "connectors": {}}}))


_INTERFERENCE = [_peer_selects_pin, _profile_selects_pin, _pin_refreshed, _gone, _emptied, _replaced]
_INTERFERENCE_IDS = ["peer-selects-pin", "profile-selects-pin", "pin-refreshed", "deleted", "emptied", "replaced"]


def _repin_with_interference(app, monkeypatch, doc, path, interfere, window, args):
    """Run --repin while *interfere* changes config.yaml: during the prompt
    (interactive) or while the pack is validated (--yes --json)."""
    asked: list = []
    actions = [lambda: interfere(doc, path)]
    if window == "prompt":
        monkeypatch.setattr(cmd_guardrail, "_confirm_proceed", _confirm_after(actions, asked))
        argv = ["use-pack", "team", *args, "--repin"]
    else:

        def _validate(pack_path, **kwargs):
            if actions:
                actions.pop(0)()
            return _valid(pack_path, **kwargs)

        monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _validate)
        argv = ["use-pack", "team", *args, "--repin", "--yes", "--json"]
    result = CliRunner().invoke(cmd_guardrail.guardrail, argv, obj=app)
    out = " ".join(result.output.split())
    if window == "validation":
        payload = json.loads(result.output)
        assert payload["ok"] is False
        out = payload["message"]
    return result, out, asked


@pytest.mark.parametrize("args", [["--connector", "codex"], []], ids=["connector", "global"])
@pytest.mark.parametrize("window", ["prompt", "validation"])
@pytest.mark.parametrize("interfere", _INTERFERENCE, ids=_INTERFERENCE_IDS)
def test_repin_writes_nothing_when_config_changed_since_its_read(on_disk, monkeypatch, interfere, window, args):
    """W4 lead directive (loop 1): --repin reads config.yaml once and writes
    only by compare-and-swap on that read. Any change since (another scope
    selecting the pin, a refreshed pin, the file deleted, emptied or
    replaced) aborts with "config changed, run again": no write, no second
    prompt, no audit line, and the file stays as the other party left it
    (a deleted config.yaml is never recreated)."""
    app, writes, conflicts, _edit, doc, path = on_disk
    result, out, asked = _repin_with_interference(app, monkeypatch, doc, path, interfere, window, args)

    assert result.exit_code == 1, result.output
    assert "config changed, run again" in out and "Nothing was changed" in out
    assert writes == [] and len(conflicts) == 1
    assert len(asked) == (1 if window == "prompt" else 0)
    assert "Re-pinned" not in out
    left = None if interfere is _gone else path.read_bytes()
    assert path.exists() is (left is not None)
    app.logger.log_config_change.assert_not_called()


@pytest.mark.parametrize(
    "interfere", [_peer_selects_pin, _gone, _emptied, _replaced], ids=["peer", "deleted", "emptied", "replaced"]
)
def test_repin_with_the_real_writer_never_writes_a_changed_or_deleted_config(on_disk, monkeypatch, interfere):
    """The same compare-and-swap through config_writer itself: the bytes the
    other party left stay byte for byte, and a deleted file stays deleted."""
    app, _writes, _conflicts, _edit, doc, path = on_disk
    monkeypatch.setattr(config_writer, "apply", _REAL_APPLY)
    after: list = []

    def _interfere(doc, path):
        interfere(doc, path)
        after.append(path.read_bytes() if path.exists() else None)

    result, out, _asked = _repin_with_interference(
        app, monkeypatch, doc, path, _interfere, "prompt", ["--connector", "codex"]
    )

    assert result.exit_code == 1, result.output
    assert "config changed, run again" in out
    assert (path.read_bytes() if path.exists() else None) == after[0]
    app.logger.log_config_change.assert_not_called()


def test_repin_preview_lists_every_config_change_it_writes(env, monkeypatch):
    """W4 lead directive (loop 1): the --repin prompt and the --json refusal
    show exactly the edits the write makes (the new pin, the pack, cleared
    connector packs, a dropped pin) and name the automatic-protection scope
    that also gets the edited pack; application_protection is not written."""
    app, _root, custom, writes = env
    old = custom.parent / "old"
    (old / "rules").mkdir(parents=True)
    gc = app.cfg.guardrail
    gc.custom_packs = {
        "team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64),
        "old": CustomRulePack(path=str(old), digest="sha256:" + "d" * 64),
    }
    gc.connectors = {
        "codex": PerConnectorGuardrailConfig(rule_pack="team"),
        "claudecode": PerConnectorGuardrailConfig(rule_pack="old"),
    }
    _app_protection(app, {"enabled": True, "guardrail": {"rule_pack": "team"}})
    _persist(app)

    declined = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", "team", "--repin"], obj=app, input="n\n")
    assert declined.exit_code == 1 and writes == [], declined.output
    unattended = _run(app, ["use-pack", "team", "--repin", "--json"])
    assert unattended.exit_code == 2 and writes == [], unattended.output
    refusal = json.loads(unattended.output)["message"]
    scripted = _run(app, ["use-pack", "team", "--repin", "--yes", "--json"])
    assert scripted.exit_code == 0, scripted.output

    planned = cmd_guardrail._planned_change_lines(writes[-1])
    assert "remove guardrail.connectors.claudecode.rule_pack" in planned
    assert "remove guardrail.custom_packs.old" in planned
    assert any(line.startswith("set guardrail.custom_packs.team = ") and "a" * 64 in line for line in planned)
    assert "set guardrail.rule_pack = team" in planned
    for line in planned:
        assert f"    {line}" in declined.output.splitlines(), line
        assert line in refusal, line
    assert "application_protection.guardrail" in " ".join(declined.output.split())
    assert "application_protection.guardrail" in refusal
    assert not any(c.path.startswith("application_protection") for c in writes[-1])


@pytest.mark.parametrize("state", ["missing", "empty", "blank"])
@pytest.mark.parametrize("pack", ["team", "path", "new-path"])
def test_repin_refuses_without_a_config_on_disk(env, tmp_path, pack, state):
    """The pins in memory (loaded before config.yaml went away) are not a
    snapshot of the file: --repin refuses, by name, by path and for a pack
    with no pin yet, and never creates config.yaml."""
    app, _root, custom, writes = env
    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="team")}
    fresh = tmp_path / "packs" / "fresh"
    (fresh / "rules").mkdir(parents=True)
    target = {"team": "team", "path": str(custom), "new-path": str(fresh)}[pack]
    path = config_mod.config_path_for_data_dir(app.cfg.data_dir)
    if state != "missing":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("" if state == "empty" else "\n# nothing here\n")

    for args in (["--yes", "--json"], ["--yes"], []):
        result = CliRunner().invoke(
            cmd_guardrail.guardrail,
            ["use-pack", target, "--connector", "codex", "--repin", *args],
            obj=app,
            input="y\n",
        )
        out = " ".join(result.output.split())
        assert result.exit_code == 1, result.output
        if "--json" in args:
            payload = json.loads(result.output)
            assert payload["ok"] is False
            out = payload["message"]
        assert "--repin replaces a pin in config.yaml" in out and "Nothing was changed" in out
        assert ("is empty" in out) is (state != "missing")
        assert "Re-pin" not in out
    assert writes == []
    assert path.exists() is (state != "missing")
    app.logger.log_config_change.assert_not_called()


def _app_protection(app, raw: dict) -> None:
    """Load an application_protection block the way the config loader does."""
    app.cfg.application_protection = config_mod._merge_application_protection(raw)


@pytest.mark.parametrize(
    ("args", "raw", "named"),
    [
        (
            ["--connector", "codex"],
            {"enabled": True, "guardrail": {"rule_pack": "team"}},
            "automatic protection (connectors it protects that are not set up manually) "
            "(application_protection.guardrail)",
        ),
        (
            ["--connector", "codex"],
            {"enabled": True, "connectors": {"claudecode": {"guardrail": {"rule_pack": "team"}}}},
            "automatic protection for Claude Code (application_protection.connectors.claudecode.guardrail)",
        ),
        (
            [],
            {"enabled": True, "connectors": {"claudecode": {"guardrail": {"rule_pack": "team"}}}},
            "automatic protection for Claude Code (application_protection.connectors.claudecode.guardrail)",
        ),
        (
            ["--connector", "codex"],
            {"enabled": False, "guardrail": {"rule_pack": "team"}},
            "(application_protection.guardrail, when turned on)",
        ),
        (
            ["--connector", "codex"],
            {"enabled": True, "connectors": {"claudecode": {"enabled": False, "guardrail": {"rule_pack": "team"}}}},
            "(application_protection.connectors.claudecode.guardrail, when turned on)",
        ),
    ],
    ids=["global", "connector", "global-repin", "off", "connector-off"],
)
def test_repin_names_automatic_protection_scopes_that_share_the_pin(env, args, raw, named):
    """W4 review loop 1: an application_protection pack that selects the same
    custom_packs key enforces the edited pack too, so the --repin prompt, the
    --json refusal, the result and the audit line name it."""
    app, _root, custom, writes = env
    gc = app.cfg.guardrail
    gc.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    gc.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="team")}
    _app_protection(app, raw)
    _persist(app)
    note = "The pin is shared, so the edited pack also applies to "

    unattended = _run(app, ["use-pack", "team", *args, "--repin", "--json"])
    assert unattended.exit_code == 2 and writes == [], unattended.output
    message = json.loads(unattended.output)["message"]
    assert note in message and named in message

    declined = CliRunner().invoke(cmd_guardrail.guardrail, ["use-pack", "team", *args, "--repin"], obj=app, input="n\n")
    assert declined.exit_code == 1 and writes == [], declined.output
    assert named in " ".join(declined.output.split())

    scripted = _run(app, ["use-pack", "team", *args, "--repin", "--yes", "--json"])
    assert scripted.exit_code == 0, scripted.output
    assert named in json.loads(scripted.output)["message"]
    audit = app.logger.log_config_change.call_args.args[-1]
    assert "repin_shared=" in audit and "application_protection." in audit
    # use-pack never writes the automatic-protection block.
    assert not any(c.path.startswith("application_protection") for c in writes[-1])


def test_automatic_protection_pack_on_another_pin_is_not_named(env):
    app, _root, custom, _writes = env
    gc = app.cfg.guardrail
    gc.custom_packs = {
        "team": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64),
        "other": CustomRulePack(path=str(custom.parent / "other"), digest="sha256:" + "d" * 64),
    }
    gc.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="team")}
    _app_protection(app, {"enabled": True, "guardrail": {"rule_pack": "other"}})
    _persist(app)
    result = _run(app, ["use-pack", "team", "--connector", "codex", "--repin", "--yes", "--json"])
    assert result.exit_code == 0, result.output
    assert "shared" not in json.loads(result.output)["message"]


@pytest.mark.parametrize(
    "raw",
    [
        {"enabled": True, "guardrail": {"rule_pack": "team"}},
        {"enabled": False, "connectors": {"claudecode": {"guardrail": {"rule_pack": "team"}}}},
    ],
    ids=["global", "connector"],
)
def test_switching_away_keeps_a_pin_automatic_protection_still_selects(env, raw):
    """W4 review loop 1: the unused-pin cleanup counts automatic-protection
    packs, so moving the last guardrail scope off a pack never unpins a pack
    application_protection still loads."""
    app, _root, custom, writes = env
    gc = app.cfg.guardrail
    gc.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)}
    gc.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="team")}
    _app_protection(app, raw)
    for args in (["strict", "--connector", "codex"], ["strict"]):
        result = _run(app, ["use-pack", *args, "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output).get("dropped_pins", []) == []
        assert not any(c.path == "guardrail.custom_packs.team" for c in writes[-1])


def test_config_loader_keeps_the_automatic_protection_pack():
    """The CLI reads (and saves) application_protection rule_pack, as the gateway does."""
    ap = config_mod._merge_application_protection(
        {"guardrail": {"rule_pack": "team"}, "connectors": {"codex": {"guardrail": {"rule_pack": "strict"}}}}
    )
    assert ap.guardrail.rule_pack == "team"
    assert ap.connectors["codex"].guardrail.rule_pack == "strict"
    cfg = default_config()
    cfg.application_protection = ap
    saved = config_mod._config_to_dict(cfg)["application_protection"]
    assert saved["guardrail"]["rule_pack"] == "team"
    assert saved["connectors"]["codex"]["guardrail"]["rule_pack"] == "strict"


def test_repin_of_an_unchanged_or_new_pack_needs_no_confirmation(env):
    app, _root, custom, writes = env
    _persist(app)
    first = _run(app, ["use-pack", str(custom), "--repin", "--json"])
    assert first.exit_code == 0, first.output
    assert "Re-pinned" not in json.loads(first.output)["message"]
    app.cfg.guardrail.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)}
    _persist(app)
    same = _run(app, ["use-pack", str(custom), "--repin", "--json"])
    assert same.exit_code == 0 and not any(c.path.startswith("guardrail.custom_packs") for c in writes[-1])


def test_repin_refuses_presets_and_clear(env):
    app, _root, _custom, writes = env
    _persist(app)
    assert _run(app, ["use-pack", "strict", "--repin"]).exit_code == 2
    assert _run(app, ["use-pack", "--clear", "--connector", "codex", "--repin"]).exit_code == 2
    assert writes == []


def test_directory_selection_preserves_registered_identity_and_digest(env, tmp_path):
    app, _root, custom, writes = env
    gc = app.cfg.guardrail
    gc.rule_pack = "alias"
    gc.custom_packs = {"alias": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)}
    # A different spelling of the same directory must not mint a fresh pin.
    directory = str(custom / ".." / custom.name)
    refused = _run(app, ["use-pack", directory, "--json"])
    assert refused.exit_code == 1, refused.output
    assert "config set guardrail.custom_packs.alias.digest" in json.loads(refused.output)["message"]
    assert writes == []

    gc.custom_packs["alias"].digest = "sha256:" + "a" * 64
    selected = _run(app, ["use-pack", directory, "--json"])
    assert selected.exit_code == 0, selected.output
    assert json.loads(selected.output)["pack"] == "alias"
    assert writes == [[config_writer.Change("guardrail.rule_pack", "alias")]]
    link = tmp_path / "linked-pack"
    try:
        link.symlink_to(custom, target_is_directory=True)
    except OSError:
        pass  # Windows users may not have symlink creation rights.
    else:
        gc.custom_packs["alias"].digest = "sha256:" + "b" * 64
        refused = _run(app, ["use-pack", str(link), "--json"])
        assert refused.exit_code == 1, refused.output
        assert len(writes) == 1
    # Another name for the directory must not hide a conflicting stale pin.
    gc.custom_packs["alias"].digest = "sha256:" + "a" * 64
    gc.custom_packs["other"] = CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64)
    refused = _run(app, ["use-pack", "alias", "--json"])
    assert refused.exit_code == 1, refused.output
    assert "config set guardrail.custom_packs.other.digest" in json.loads(refused.output)["message"]
    assert len(writes) == 1


def test_pack_switch_keeps_application_protection_pins(env):
    app, _root, custom, writes = env
    gc = app.cfg.guardrail
    gc.rule_pack = "team"
    gc.custom_packs = {"team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64)}
    application = app.cfg.application_protection
    application.guardrail.rule_pack = "team"
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["dropped_pins"] == []
    assert writes[-1] == [config_writer.Change("guardrail.rule_pack", "strict")]

    application.guardrail.rule_pack = ""
    application.connectors["codex"] = ApplicationProtectionConnectorConfig(
        guardrail=PerConnectorGuardrailConfig(rule_pack="team"),
    )
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["dropped_pins"] == []
    assert writes[-1] == [config_writer.Change("guardrail.rule_pack", "strict")]


def test_bare_name_selects_installed_pack_over_cwd_folder(env, tmp_path, monkeypatch):
    """GAP-1576: an unrelated ./vsg2 folder does not shadow the installed vsg2 pack."""
    app, root, _custom, writes = env
    (root / "vsg2" / "rules").mkdir(parents=True)
    workdir = tmp_path / "work"
    (workdir / "vsg2").mkdir(parents=True)
    monkeypatch.chdir(workdir)
    result = _run(app, ["use-pack", "vsg2", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["path"] == str(root / "vsg2")
    assert writes[-1][0].value["path"] == str(root / "vsg2")
    assert config_writer.Change("guardrail.rule_pack", "vsg2") in writes[-1]


def test_unknown_connector_refused(env):
    app, _root, _custom, writes = env
    result = _run(app, ["use-pack", "strict", "--connector", "claudecode"])
    assert result.exit_code == 1
    assert writes == []


def test_invalid_pack_writes_nothing(env, monkeypatch):
    app, _root, _custom, writes = env
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _invalid)
    result = _run(app, ["use-pack", "strict", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["validation"]["error"]["code"] == "bad_rule"
    assert writes == []


def test_validator_unavailable_preset_proceeds_custom_refuses(env, monkeypatch):
    """A custom pack is pinned by its validated digest, so without the
    validator it is refused even with --no-validate."""
    app, _root, custom, writes = env
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", _unavailable)

    preset = _run(app, ["use-pack", "permissive"])
    assert preset.exit_code == 0, preset.output
    assert writes[-1][0] == config_writer.Change("guardrail.rule_pack", "permissive")

    for extra in ([], ["--no-validate"]):
        refused = _run(app, ["use-pack", str(custom), *extra, "--json"])
        assert refused.exit_code == 2
        assert json.loads(refused.output)["ok"] is False
    assert len(writes) == 1


def test_clear_connector_override(env):
    app, root, custom, writes = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    result = _run(app, ["use-pack", "--clear", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connector"] == "codex"
    assert payload["path"] == str(root / "default")
    # The custom pin only codex selected goes with its pack (GAP-0127).
    assert writes == [[
        config_writer.Change("guardrail.connectors.codex.rule_pack", unset=True),
        config_writer.Change("guardrail.custom_packs.team", unset=True),
    ]]


def test_clear_connector_pack_drops_stale_rule_overrides(env, monkeypatch):
    app, _root, _custom, writes = env
    monkeypatch.setattr(policy_catalog, "pack_rule_defaults", lambda _path: {"SEC-AWS-KEY": True})
    monkeypatch.setattr(policy_catalog, "rule_defaults_with_protections", lambda _path, _packs: {"SEC-AWS-KEY": True})
    app.cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(
            rule_pack="strict", rules=GuardrailRulesConfig(disable=["SEC-ENV-DUMP-REQUEST"])
        )
    }
    result = _run(app, ["use-pack", "--clear", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    assert writes[-1] == [
        config_writer.Change("guardrail.connectors.codex.rule_pack", unset=True),
        config_writer.Change("guardrail.connectors.codex.rules.disable", unset=True, prune_empty_to="guardrail.connectors.codex"),
    ]
    assert json.loads(result.output)["dropped_rule_references"] == [
        "guardrail.connectors.codex.rules.disable: SEC-ENV-DUMP-REQUEST"
    ]


def test_global_pack_switch_keeps_profile_connector_rule_from_profile_protection(env, monkeypatch):
    app, _root, _custom, writes = env
    rule_id = "impact.sql_schema_destroy"
    protection = "database-destruction-protection"
    monkeypatch.setattr(policy_catalog, "pack_rule_defaults", lambda _path: {"other.rule": True})
    monkeypatch.setattr(
        policy_catalog,
        "rule_defaults_with_protections",
        lambda _path, packs: {"other.rule": True, **({rule_id: True} if protection in packs else {})},
    )
    app.cfg.guardrail.profiles = {
        "engineering": GuardrailProfile(
            rules=GuardrailRulesConfig(protections=[protection]),
            connectors={
                "codex": PerConnectorGuardrailConfig(
                    rules=GuardrailRulesConfig(severity_overrides={rule_id: "LOW"})
                )
            },
        )
    }
    result = _run(app, ["use-pack", "permissive", "--json"])
    assert result.exit_code == 0, result.output
    assert not any(c.path.endswith("severity_overrides") for c in writes[-1])
    assert json.loads(result.output)["dropped_rule_references"] == []


def test_usage_errors(env):
    app, _root, _custom, writes = env
    assert _run(app, ["use-pack"]).exit_code == 2
    assert _run(app, ["use-pack", "--clear"]).exit_code == 2
    assert _run(app, ["use-pack", "strict", "--clear", "--connector", "codex"]).exit_code == 2
    assert writes == []


def test_list_packs_json(env):
    app, root, custom, _writes = env
    _multi(app, {"codex": str(custom), "claudecode": ""})
    (root / "team2" / "rules").mkdir(parents=True)
    result = _run(app, ["list-packs", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == 1
    assert payload["global"] == {
        "connector": "global",
        "pack": "default",
        "path": str(root / "default"),
        "source": "global",
    }
    rows = {row["connector"]: row for row in payload["connectors"]}
    assert rows["codex"]["source"] == "override"
    assert rows["claudecode"]["pack"] == "default"
    packs = {p["name"]: p for p in payload["packs"]}
    assert packs["team2"]["kind"] == "custom"
    assert packs["team"]["used_by"] == ["codex"]
    assert packs["default"]["used_by"] == ["global", "claudecode"]

    text = _run(app, ["list-packs"])
    assert text.exit_code == 0
    assert "team2" in text.output


def test_switching_away_drops_the_unused_custom_pin(env):
    """GAP-0127: use-pack drops the custom_packs pin no scope selects any more
    and keeps the pins still in use."""
    from defenseclaw.config import CustomRulePack, GuardrailProfile

    app, _root, custom, writes = env
    gc = app.cfg.guardrail
    gc.custom_packs = {
        "team": CustomRulePack(path=str(custom), digest="sha256:" + "a" * 64),
        "ops": CustomRulePack(path=str(custom), digest="sha256:" + "b" * 64),
    }
    gc.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack="team")}
    gc.profiles = {"oncall": GuardrailProfile(rule_pack="ops")}

    result = _run(app, ["use-pack", "--clear", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["dropped_pins"] == ["team"]
    assert config_writer.Change("guardrail.custom_packs.team", unset=True) in writes[-1]
    assert not any(c.path == "guardrail.custom_packs.ops" for c in writes[-1])

    gc.rule_pack = "team"
    gc.connectors = {}
    result = _run(app, ["use-pack", "strict"])
    assert result.exit_code == 0, result.output
    assert "guardrail.custom_packs.team" in result.output
    assert config_writer.Change("guardrail.custom_packs.team", unset=True) in writes[-1]

    result = _run(app, ["use-pack", "permissive", "--connector", "codex", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["dropped_pins"] == []


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["guardrail", "use-pack", "cert-rb"], True),
        (["guardrail", "use-pack", "default", "--connector", "codex"], True),
        (["guardrail", "status"], False),
        (["guardrail", "--json", "use-pack", "x"], False),
        (["status"], False),
    ],
)
def test_use_pack_skips_the_startup_config_check(monkeypatch, argv, expected):
    """GAP-0128: use-pack re-pins an edited pack whose stale pin fails the
    start-up config check (its own write validates the candidate)."""
    import click
    from defenseclaw import main as main_module

    monkeypatch.setattr(main_module.sys, "argv", ["defenseclaw", *argv])
    ctx = click.Context(main_module.cli)
    ctx.invoked_subcommand = argv[0]
    assert main_module._is_pack_repin(ctx) is expected


def test_validate_pack_unknown_bare_name_lists_available_packs(env, monkeypatch):
    app, root, _custom, _writes = env
    monkeypatch.setattr("defenseclaw.config.load", lambda: app.cfg)
    (root / "team2" / "rules").mkdir(parents=True)
    result = _run(app, ["validate-pack", "nosuchpack"])
    assert result.exit_code != 0
    assert "no pack with the name 'nosuchpack' was found" in result.output
    assert "default" in result.output and "team2" in result.output


def test_validate_pack_unknown_bare_name_json_is_the_versioned_failure(env, monkeypatch):
    # GAP-1053: --json keeps its result document for an unknown pack name.
    app, _root, _custom, _writes = env
    monkeypatch.setattr("defenseclaw.config.load", lambda: app.cfg)
    result = CliRunner().invoke(
        cmd_guardrail.guardrail, ["validate-pack", "definitely-missing-pack", "--json"], obj=app,
    )
    assert result.exit_code == 1, result.output
    document = json.loads(result.stdout)
    assert document["wire_version"] == rulepack_validation.RULEPACK_WIRE_VERSION
    assert (document["kind"], document["valid"]) == ("validation_error", False)
    assert document["error"]["code"] == "pack_not_found"
    assert "definitely-missing-pack" in document["error"]["reason"]
