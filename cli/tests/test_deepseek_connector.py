# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Preview discovery/readiness must neither fall back nor claim fail-closed."""
from types import SimpleNamespace

from defenseclaw import connector_paths, fail_mode
from defenseclaw.commands import cmd_doctor


def test_deepseek_home_redirects_only_its_own_files(monkeypatch, tmp_path):
    root = tmp_path / "dsh home"
    monkeypatch.setenv("DSH_HOME", str(root))
    assert connector_paths.connector_home("deepseek") == str(root)
    assert set(connector_paths.connector_config_files("deepseek")) == {
        str(root / "defenseclaw-hooks.json"), str(root / "cordis.patch.yml")
    }


def test_deepseek_effective_fail_mode_is_open_even_when_global_closed():
    cfg = SimpleNamespace(guardrail=SimpleNamespace(hook_fail_mode="closed"))
    report = fail_mode.connector_fail_mode_report(cfg, "deepseek")
    assert report["configured"] == "closed"
    assert report["effective"] == "open"
    assert report["provenance"] == "deepseek-upstream-fail-open"


def test_deepseek_doctor_requires_both_documents(monkeypatch, tmp_path):
    hooks = tmp_path / "defenseclaw-hooks.json"
    patch = tmp_path / "cordis.patch.yml"
    hooks.write_text('deepseek-hook.sh', encoding="utf-8")
    monkeypatch.setattr(cmd_doctor, "_hook_health_paths_from_lock", lambda *_: [str(hooks), str(patch)])
    rows = []
    monkeypatch.setattr(cmd_doctor, "_emit", lambda status, label, detail, **_: rows.append((status, detail)))
    result = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_connector_hooks(SimpleNamespace(), "deepseek", result)
    assert rows[-1][0] == "fail"
    patch.write_text('defenseclaw-deepseek', encoding="utf-8")
    cmd_doctor._check_connector_hooks(SimpleNamespace(), "deepseek", result)
    assert rows[-1][0] == "pass"
    assert "live runtime unverified" in rows[-1][1]
