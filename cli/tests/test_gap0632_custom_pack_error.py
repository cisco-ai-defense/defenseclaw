# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0632: a broken ``guardrail.custom_packs`` entry is one config error.

Mirrors Go ``Config.CustomRulePackError``: the selection loads its built-in
fallback pack, the hook's outage mode follows the strict tier (closed), and
``doctor`` names the entry's error; a usable entry keeps its own folder.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from defenseclaw import config as dcconfig
from defenseclaw import policy_catalog, rulepack_validation
from defenseclaw.commands.cmd_doctor import _DoctorResult, _emit_custom_pack_config_error
from defenseclaw.config import Config, CustomRulePack

PIN = "sha256:" + "a" * 64


def _cfg(tmp_path, name: str, entry: CustomRulePack) -> Config:
    cfg = Config()
    cfg.data_dir = str(tmp_path / "data")
    cfg.guardrail.rule_pack = name
    cfg.guardrail.custom_packs = {name: entry}
    return cfg


def _pack(tmp_path, name: str = "pack") -> str:
    path = tmp_path / name
    path.mkdir(exist_ok=True)
    (path / "suppressions.yaml").write_text("version: 1\n", encoding="utf-8")
    return str(path)


class _Loader:
    """A stand-in for the Go rule loader helper: it answers by the pack folder."""

    def __init__(self) -> None:
        self.calls = 0
        self.answers: dict[str, object] = {}

    def __call__(self, path, *, gateway_binary=None):
        self.calls += 1
        answer = self.answers.get(os.path.basename(path), PIN.removeprefix("sha256:"))
        if answer is None:
            raise rulepack_validation.RulePackValidationBridgeError("helper unavailable", code="gateway_unavailable")
        if isinstance(answer, str) and len(answer) == 64:
            summary = {field: 0 for field in rulepack_validation._SUMMARY_COUNT_FIELDS}
            summary.update(digest=answer, files_digest=answer)
            return rulepack_validation.RulePackValidationResult(1, "validation", True, summary=summary)
        issue = rulepack_validation.RulePackValidationIssue(path=".", code="pack_empty", reason=str(answer))
        return rulepack_validation.RulePackValidationResult(1, "validation_error", False, error=issue)


# The reader conftest replaces for every test (an installed gateway must not decide them).
_REAL_LOADER_VERDICT = policy_catalog._loader_verdict


@pytest.fixture
def loader(monkeypatch):
    fake = _Loader()
    monkeypatch.setattr(rulepack_validation, "validate_rule_pack", fake)
    monkeypatch.setattr(policy_catalog, "_loader_verdict", _REAL_LOADER_VERDICT)
    return fake


def _expect_config_error(cfg, name: str, fallback: str) -> None:
    assert policy_catalog.custom_pack_problem(cfg, name)
    assert os.path.basename(cfg.guardrail.effective_rule_pack_dir("codex")) == fallback
    assert cfg.guardrail.hook_policy_tier("codex") == "strict"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "closed"
    result = _DoctorResult()
    _emit_custom_pack_config_error(cfg.guardrail, cfg, "codex", result)
    (row,) = result.checks
    assert row["status"] == "fail" and f"built-in {fallback} pack" in row["detail"]


@pytest.mark.parametrize("name", ["strict", "default", "operator"])
def test_pack_the_go_loader_refuses_is_a_config_error(tmp_path, loader, name):
    """Python takes the Go loader verdict: a pack that does not load is a config error with the built-in fallback."""
    folder = _pack(tmp_path, "copy")
    loader.answers["copy"] = "the folder holds no pack files"
    cfg = _cfg(tmp_path, name, CustomRulePack(path=folder, digest=PIN))
    _expect_config_error(cfg, name, name if name in policy_catalog.RULE_PACK_PRESETS else "default")


@pytest.mark.parametrize("name", ["strict", "default", "operator"])
@pytest.mark.parametrize("variant", ["wrong pin", "missing pin"])
def test_stale_pin_is_refused_not_replaced_by_a_builtin_pack(tmp_path, loader, name, variant):
    """A valid pack whose files do not hash to the pin is an integrity refusal (Go StalePinError).

    The entry keeps its folder (the gateway refuses it), no built-in pack is
    named as its replacement, and the hook stays on the strict tier (closed).
    """
    folder = _pack(tmp_path, "copy")
    pin = {"wrong pin": "sha256:" + "b" * 64, "missing pin": ""}[variant]
    cfg = _cfg(tmp_path, name, CustomRulePack(path=folder, digest=pin))
    problem = policy_catalog.custom_pack_problem(cfg, name)
    assert isinstance(problem, policy_catalog.StalePinProblem)
    assert f"guardrail.custom_packs.{name}.digest" in problem
    assert not policy_catalog.custom_pack_falls_back(cfg, name)
    assert cfg.guardrail.effective_rule_pack_dir("codex") == folder
    assert cfg.guardrail.hook_policy_tier("codex") == "strict"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "closed"
    result = _DoctorResult()
    _emit_custom_pack_config_error(cfg.guardrail, cfg, "codex", result)
    (row,) = result.checks
    assert row["status"] == "fail"
    assert "refuses the pack until the pin matches the files" in row["detail"]
    assert "built-in" not in row["detail"]


@pytest.mark.parametrize("name", ["strict", "operator"])
def test_pack_the_loader_cannot_vouch_for_grants_no_open_outage(tmp_path, loader, name):
    """No loader verdict (no trusted gateway binary) is not a usable pack: strict, as the standalone hook without the loader."""
    loader.answers["pack"] = None
    cfg = _cfg(tmp_path, name, CustomRulePack(path=_pack(tmp_path), digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, name) == ""
    assert cfg.guardrail.hook_policy_tier("codex") == "strict"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "closed"


def test_pin_comparison_is_case_insensitive_and_needs_the_prefix(tmp_path, loader):
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path=_pack(tmp_path), digest=PIN.upper().replace("SHA256", "sha256")))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    bare = _cfg(tmp_path, "operator", CustomRulePack(path=_pack(tmp_path), digest=PIN.removeprefix("sha256:")))
    assert policy_catalog.custom_pack_problem(bare, "operator")


def test_loader_verdict_is_never_kept_between_reads(tmp_path, loader):
    """Every read asks the loader: no cache can hold a usable verdict for a pack that changed."""
    path = _pack(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path=path, digest=PIN))
    for _ in range(3):
        assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    assert loader.calls == 3


def test_a_directory_entry_added_to_a_valid_pack_reaches_the_next_reader(tmp_path, loader):
    """The Go loader refuses a directory link in a pack; a verdict taken before it must not survive."""
    path = _pack(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path=path, digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    assert cfg.guardrail.hook_policy_tier("codex") == "default"
    os.symlink(str(tmp_path), os.path.join(path, "linked"))
    loader.answers[os.path.basename(path)] = "file_type: a directory link"
    reloaded = _cfg(tmp_path, "operator", CustomRulePack(path=path, digest=PIN))
    for view in (cfg, reloaded):
        assert policy_catalog.custom_pack_problem(view, "operator")
        assert view.guardrail.hook_policy_tier("codex") == "strict"
        assert view.guardrail.effective_hook_outage_fail_mode("codex") == "closed"


def test_an_edit_that_keeps_size_and_mtime_reaches_the_next_reader(tmp_path, loader):
    path = _pack(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path=path, digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    target = os.path.join(path, "suppressions.yaml")
    before = os.stat(target)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write("version: 2\n")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert os.stat(target).st_size == before.st_size
    loader.answers[os.path.basename(path)] = "the pack content changed"
    assert policy_catalog.custom_pack_problem(cfg, "operator")


def test_loaded_relative_config_path_survives_chdir_and_copies(tmp_path, monkeypatch, loader):
    """A relative DEFENSECLAW_CONFIG: the pack folder is fixed when the config is loaded, for the config and its copies."""
    import copy

    home = tmp_path / "work"
    (home / "cfg" / "pack").mkdir(parents=True)
    (home / "cfg" / "pack" / "suppressions.yaml").write_text("version: 1\n", encoding="utf-8")
    (home / "cfg" / "config.yaml").write_text(
        "guardrail:\n  rule_pack: operator\n  custom_packs:\n    operator:\n"
        f"      path: pack\n      digest: {PIN}\n",
        encoding="utf-8",
    )
    (tmp_path / "other" / "cfg").mkdir(parents=True)
    monkeypatch.chdir(home)
    monkeypatch.setenv("DEFENSECLAW_CONFIG", os.path.join("cfg", "config.yaml"))
    cfg = dcconfig.load(data_dir=str(tmp_path / "data"))
    want = str(home / "cfg" / "pack")
    copies = (cfg, copy.copy(cfg), copy.deepcopy(cfg), copy.copy(cfg.guardrail), copy.deepcopy(cfg.guardrail))
    for view in copies:
        guardrail = getattr(view, "guardrail", view)
        owner = SimpleNamespace(guardrail=guardrail, data_dir="")
        assert policy_catalog.custom_pack_dir(owner, guardrail.custom_packs["operator"]) == want
    monkeypatch.chdir(tmp_path / "other")
    for view in copies:
        guardrail = getattr(view, "guardrail", view)
        owner = SimpleNamespace(guardrail=guardrail, data_dir="")
        assert policy_catalog.custom_pack_dir(owner, guardrail.custom_packs["operator"]) == want
        assert policy_catalog.custom_pack_problem(owner, "operator") == ""
        assert guardrail.effective_rule_pack_dir("codex") == want
        assert guardrail.hook_policy_tier("codex") == "default"
        assert guardrail.effective_hook_outage_fail_mode("codex") == "open"


def test_relative_config_directory_is_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dcconfig, "config_path_for_data_dir", lambda _data_dir=None: os.path.join("cfg", "config.yaml"))
    got = policy_catalog.custom_pack_dir(Config(), CustomRulePack(path="pack", digest=PIN))
    os.chdir(os.path.dirname(tmp_path))
    assert got == str(tmp_path / "cfg" / "pack")


@pytest.mark.parametrize("name", ["strict", "default", "operator"])
@pytest.mark.parametrize("variant", ["blank path", "empty file set", "missing folder"])
def test_broken_entry_is_a_config_error_with_builtin_fallback(tmp_path, name, variant):
    entry = {
        "blank path": CustomRulePack(path="  ", digest=PIN),
        "empty file set": CustomRulePack(path=_pack(tmp_path), digest=policy_catalog.EMPTY_RULE_PACK_FILES_DIGEST.upper()),
        "missing folder": CustomRulePack(path=str(tmp_path / "missing"), digest=PIN),
    }[variant]
    cfg = _cfg(tmp_path, name, entry)
    problem = policy_catalog.custom_pack_problem(cfg, name)
    assert f"guardrail.custom_packs.{name}" in problem
    fallback = name if name in policy_catalog.RULE_PACK_PRESETS else "default"
    assert policy_catalog.builtin_rule_pack_fallback(name) == fallback
    assert os.path.basename(cfg.guardrail.effective_rule_pack_dir("codex")) == fallback
    assert cfg.guardrail.hook_policy_tier("codex") == "strict"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "closed"

    result = _DoctorResult()
    _emit_custom_pack_config_error(cfg.guardrail, cfg, "codex", result)
    (row,) = result.checks
    assert row["status"] == "fail"
    assert f"guardrail.custom_packs.{name}" in row["detail"]
    assert f"built-in {fallback} pack" in row["detail"]
    assert "fail closed" in row["detail"]


def test_usable_entry_keeps_its_folder_and_posture(tmp_path, loader):
    path = _pack(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path=path, digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    assert cfg.guardrail.effective_rule_pack_dir("codex") == path
    assert cfg.guardrail.hook_policy_tier("codex") == "default"
    assert cfg.guardrail.effective_hook_outage_fail_mode("codex") == "open"
    result = _DoctorResult()
    _emit_custom_pack_config_error(cfg.guardrail, cfg, "codex", result)
    assert result.checks == []


def test_relative_path_is_relative_to_the_config_directory(tmp_path, monkeypatch, loader):
    config_dir = tmp_path / "home"
    config_dir.mkdir()
    pack = _pack(config_dir)
    monkeypatch.setattr(dcconfig, "config_path_for_data_dir", lambda _data_dir=None: config_dir / "config.yaml")
    monkeypatch.chdir(tmp_path)
    cfg = _cfg(tmp_path, "operator", CustomRulePack(path="pack", digest=PIN))
    assert policy_catalog.custom_pack_problem(cfg, "operator") == ""
    assert cfg.guardrail.effective_rule_pack_dir("codex") == pack
    # "~" is not expanded: the gateway reads it as a relative path.
    tilde = _cfg(tmp_path, "operator", CustomRulePack(path="~/pack", digest=PIN))
    assert policy_catalog.custom_pack_problem(tilde, "operator")
