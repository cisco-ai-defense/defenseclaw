# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""One table for every installed Kiro form (rel-1-0-4 GAP-0895, GAP-0828, GAP-0829).

The rows are internal/enterprisehooks/testdata/kiro_forms_table.json, the table
Go's TestKiroFormsTable holds AssessKiro, the managed installer and both
enumerators to. Here the same rows hold Python's assess_kiro, setup's version
gate and doctor's connector health. Each form (kiro-cli, each Kiro IDE
install) is judged on its own; a form whose version could not be read is
unknown, and unknown is not protected.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import doctor_health
from defenseclaw.commands import cmd_setup
from defenseclaw.connector_contracts import assess_kiro_signal
from defenseclaw.doctor_health import HealthStatus
from defenseclaw.inventory import agent_discovery as ad

TABLE = Path(__file__).resolve().parents[2] / "internal" / "enterprisehooks" / "testdata" / "kiro_forms_table.json"
ROWS = json.loads(TABLE.read_text(encoding="utf-8"))["rows"]
UNREADABLE = "unreadable"
FORM_ORDER = ("cli", "ide_user", "ide_machine")


def _signal(row: dict) -> SimpleNamespace:
    """The discovery signal _scan_agent records for the row's installs."""

    forms = []
    for name in FORM_ORDER:
        value = row["forms"].get(name)
        if value is None:
            continue
        kind = "cli" if name == "cli" else "ide"
        path = f"/opt/{name}/kiro" + ("-cli" if kind == "cli" else "")
        if value == UNREADABLE:
            unread = f"{path} is installed, but its version could not be read (exit 1)"
            forms.append({"kind": kind, "version": "", "unread": unread, "path": path})
        else:
            version = f"kiro-cli {value}" if kind == "cli" else value
            forms.append({"kind": kind, "version": version, "unread": "", "path": path})
    read = [form for form in forms if form["version"]]
    assessment = assess_kiro_signal(SimpleNamespace(kiro_forms=forms))
    selected = next((f for f in read if assessment.selected and f["version"] == assessment.selected.version), None)
    selected = selected or (read[0] if read else None)
    return SimpleNamespace(
        name="kiro",
        installed=bool(forms),
        config_path="",
        binary_path=(selected or (forms[0] if forms else {"path": ""}))["path"],
        version=selected["version"] if selected else "",
        error="" if selected or not forms else "exit 1",
        kiro_cli_version=next((f["version"] for f in read if f["kind"] == "cli"), ""),
        kiro_ide_version=next((f["version"] for f in read if f["kind"] == "ide"), ""),
        kiro_forms=forms,
    )


def _word(admitted: bool) -> str:
    return "admitted" if admitted else "refused"


@pytest.mark.parametrize("row", ROWS, ids=[row["name"] for row in ROWS])
def test_kiro_forms_table(row: dict, tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", raising=False)
    signal = _signal(row)

    # assess_kiro: each form's verdict, the form setup covers, the refusals.
    assessment = assess_kiro_signal(signal)
    expected = [row["verdicts"][name] for name in FORM_ORDER if name in row["forms"]]
    got = ["protected" if form.protected else form.code for form in assessment.forms]
    assert got == expected
    assert all(form.reason for form in assessment.unprotected())
    enroll = row["enroll"]
    assert (assessment.selected.kind if assessment.selected else "") == ("" if not enroll else enroll.split("_")[0])
    assert _word(not assessment.action_refusal) == row["action"]
    assert _word(not assessment.every_mode_refusal) == row["observe"]

    # Setup's version gate, in both modes.
    discovery = SimpleNamespace(agents={"kiro": signal})
    for mode in ("action", "observe"):
        scope: dict = {}
        admitted = cmd_setup._check_connector_version_supported_for_setup(
            "kiro", mode=mode, emit=False, data_dir=str(tmp_path), _allow_prompt=False,
            _discovery=discovery, _refusal_scope=scope,
        )
        assert _word(admitted) == row[mode], mode
        if mode == "action" and not admitted:
            # An action refusal falls back to observe only when observe admits it.
            assert cmd_setup._observe_fallback_admitted(scope) == (row["observe"] == "admitted")

    # Doctor: the protected form is supported and each other form has a finding.
    findings = doctor_health.assess_connector_health(("kiro",), discovery)
    statuses = {finding.status for finding in findings}
    overall = (
        "supported" if HealthStatus.SUPPORTED in statuses
        else "unsupported" if HealthStatus.UNSUPPORTED in statuses
        else "untested" if HealthStatus.UNTESTED in statuses
        else "unavailable"
    )
    assert overall == row["doctor"]
    if row["forms"]:
        not_supported = [finding for finding in findings if finding.status is not HealthStatus.SUPPORTED]
        assert len(not_supported) == len(assessment.unprotected())
        if assessment.selected is not None:
            assert all(finding.reason_code.endswith("-auxiliary") for finding in not_supported)


def test_failed_kiro_probe_is_an_installed_unknown_form(monkeypatch, tmp_path) -> None:
    """GAP-0895: a kiro-cli whose --version fails was not installed, so action
    setup admitted Kiro as not gated. It is installed with an unknown version:
    action refuses and observe warns. Beside a supported IDE it is still named."""

    cli, ide = "/usr/local/bin/kiro-cli", "/usr/local/bin/kiro"
    monkeypatch.delenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", raising=False)
    monkeypatch.setattr(ad, "_agent_config_path", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(ad, "_missing_probe_state", lambda *_args: ([], []))
    for candidates, error in (((cli,), "exit status 1"), ((cli,), ad.VERSION_PROBE_TIMED_OUT), ((cli, ide), "exit status 1")):
        monkeypatch.setattr(ad, "_binary_candidates_for_agent", lambda *_args, c=candidates: c)
        monkeypatch.setattr(
            ad, "_version_for_agent_binary",
            lambda _name, path, _args, error=error, **_kwargs: ("", error) if path == cli else ("1.0.190", ""),
        )
        signal = ad._scan_agent("kiro")
        assert signal.installed, (candidates, error)
        assessment = assess_kiro_signal(signal)
        unknown = [form for form in assessment.forms if form.kind == "cli"]
        assert len(unknown) == 1 and unknown[0].unknown and cli in unknown[0].reason
        discovery = SimpleNamespace(agents={"kiro": signal})
        action = cmd_setup._check_connector_version_supported_for_setup(
            "kiro", mode="action", emit=False, data_dir=str(tmp_path), _allow_prompt=False, _discovery=discovery,
        )
        assert action == (ide in candidates), (candidates, error)
        assert cmd_setup._check_connector_version_supported_for_setup(
            "kiro", mode="observe", emit=False, data_dir=str(tmp_path), _allow_prompt=False, _discovery=discovery,
        )
        # The forms survive the discovery cache doctor reads.
        cached = ad.AgentSignal(**{**vars(signal)})
        assert ad._kiro_forms_from_cache(json.loads(json.dumps(cached.kiro_forms))) == signal.kiro_forms
