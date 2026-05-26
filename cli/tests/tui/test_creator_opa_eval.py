# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 9: ``opa_eval`` subprocess wrapper tests.

These tests stand up a tiny shell-script "opa" stub on PATH so we
can pin the wrapper's behaviour without depending on a real OPA
install on the developer's machine. The stub mirrors the JSON shape
``opa eval --format json`` actually produces.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from defenseclaw.tui.creator import opa_eval


def _make_opa_stub(
    tmp_path: Path,
    *,
    verdict_value: Any = "allowed",
    reason_value: Any = "no findings",
    exit_code: int = 0,
    sleep_seconds: float = 0.0,
    stderr_text: str = "",
    stdout_override: str | None = None,
) -> Path:
    """Materialize a minimal POSIX shell stub at ``tmp_path/opa``.

    Returns the path to the executable. The stub picks the verdict
    or reason output based on the last argv (``data.<entrypoint>``)
    so a single instance can serve both calls in
    ``evaluate_domain``.
    """
    if stdout_override is not None:
        # Always emit via heredoc so payloads that aren't valid bash
        # (e.g. raw "not-json" or "{}" with shell metachars) don't
        # blow up before reaching our wrapper.
        stdout = (
            f"cat <<__OVERRIDE_EOF__\n{stdout_override}\n__OVERRIDE_EOF__\n"
        )
    else:
        verdict_block = json.dumps(
            {"result": [{"expressions": [{"value": verdict_value}]}]}
        )
        reason_block = json.dumps(
            {"result": [{"expressions": [{"value": reason_value}]}]}
        )
        # The shell script picks branch by inspecting the trailing
        # argument the wrapper passed.
        stdout = (
            f'if [[ "${{!#}}" == *.reason || "${{!#}}" == *.rule_name '
            f'|| "${{!#}}" == *.retain_reason ]]; then\n'
            f"  cat <<__REASON_EOF__\n{reason_block}\n__REASON_EOF__\nelse\n"
            f"  cat <<__VERDICT_EOF__\n{verdict_block}\n__VERDICT_EOF__\nfi\n"
        )

    sleep_line = f"sleep {sleep_seconds}\n" if sleep_seconds > 0 else ""
    stderr_line = (
        f'printf "{stderr_text}" 1>&2\n' if stderr_text else ""
    )
    script = (
        "#!/bin/bash\n"
        f"{sleep_line}"
        f"{stderr_line}"
        f"{stdout}"
        f"exit {exit_code}\n"
    )

    opa_path = tmp_path / "opa"
    opa_path.write_text(script, encoding="utf-8")
    opa_path.chmod(opa_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return opa_path


@pytest.fixture
def opa_stub(tmp_path: Path):
    """Return a builder fn that creates an opa stub at ``tmp_path/opa``."""

    def _builder(**kwargs: Any) -> Path:
        return _make_opa_stub(tmp_path, **kwargs)

    return _builder


def _config_for(stub: Path, *, rego_dir: Path | None = None) -> opa_eval.OpaConfig:
    return opa_eval.OpaConfig(
        rego_dir=rego_dir or stub.parent,
        opa_bin=str(stub),
        timeout_seconds=2.0,
    )


# --- domain_entrypoints --------------------------------------------------


def test_domain_entrypoints_pinned_for_known_domains() -> None:
    """Pin every known-domain entrypoint pair so a renames are
    forced to land in this module + the web Creator together."""
    assert opa_eval.domain_entrypoints("admission") == (
        "defenseclaw.admission.verdict",
        "defenseclaw.admission.reason",
    )
    assert opa_eval.domain_entrypoints("guardrail") == (
        "defenseclaw.guardrail.severity",
        "defenseclaw.guardrail.reason",
    )
    assert opa_eval.domain_entrypoints("firewall") == (
        "defenseclaw.firewall.action",
        "defenseclaw.firewall.rule_name",
    )
    assert opa_eval.domain_entrypoints("audit") == (
        "defenseclaw.audit.retain",
        "defenseclaw.audit.retain_reason",
    )
    assert opa_eval.domain_entrypoints("skill_actions") == (
        "defenseclaw.skill_actions.runtime_action",
        None,
    )


def test_domain_entrypoints_falls_back_to_default_verdict_path() -> None:
    """Custom domains use the conventional ``defenseclaw.<x>.verdict``
    rule with no reason path."""
    assert opa_eval.domain_entrypoints("my-custom") == (
        "defenseclaw.my-custom.verdict",
        None,
    )


# --- is_opa_available ----------------------------------------------------


def test_is_opa_available_true_when_stub_on_path(
    opa_stub, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub = opa_stub()
    monkeypatch.setenv("PATH", str(tmp_path), prepend=os.pathsep)
    assert opa_eval.is_opa_available(opa_bin=str(stub))


def test_is_opa_available_false_when_binary_missing(tmp_path: Path) -> None:
    assert not opa_eval.is_opa_available(opa_bin=str(tmp_path / "nope"))


# --- evaluate_entrypoint -------------------------------------------------


def test_evaluate_entrypoint_returns_value_for_defined_rule(opa_stub) -> None:
    stub = opa_stub(verdict_value="allowed")
    config = _config_for(stub)
    result = opa_eval.evaluate_entrypoint(
        config,
        "defenseclaw.admission.verdict",
        input_payload={"hook": "ai-call"},
        data_payload={"actions": {"HIGH": {"runtime": "block"}}},
    )
    assert result == "allowed"


def test_evaluate_entrypoint_returns_none_for_undefined_rule(
    opa_stub, tmp_path: Path
) -> None:
    """The wrapper collapses ``{"result": []}`` to ``None`` so callers
    can fall back to a rule default."""
    empty_payload = json.dumps({"result": []})
    stub = opa_stub(stdout_override=empty_payload)
    config = _config_for(stub)
    assert (
        opa_eval.evaluate_entrypoint(
            config,
            "defenseclaw.admission.verdict",
            input_payload={},
            data_payload={},
        )
        is None
    )


def test_evaluate_entrypoint_raises_when_opa_binary_missing(tmp_path: Path) -> None:
    config = opa_eval.OpaConfig(
        rego_dir=tmp_path,
        opa_bin=str(tmp_path / "missing"),
        timeout_seconds=1.0,
    )
    with pytest.raises(opa_eval.OpaUnavailableError, match="opa binary not found"):
        opa_eval.evaluate_entrypoint(
            config, "defenseclaw.x.verdict", input_payload={}, data_payload={}
        )


def test_evaluate_entrypoint_raises_when_opa_exits_nonzero(opa_stub) -> None:
    stub = opa_stub(exit_code=1, stderr_text="parse error: blah")
    config = _config_for(stub)
    with pytest.raises(opa_eval.OpaUnavailableError, match="parse error"):
        opa_eval.evaluate_entrypoint(
            config,
            "defenseclaw.admission.verdict",
            input_payload={},
            data_payload={},
        )


def test_evaluate_entrypoint_raises_on_timeout(opa_stub) -> None:
    """A pathological policy can't lock up the TUI - the wrapper
    times out after the configured budget and surfaces an
    actionable error message."""
    stub = opa_stub(sleep_seconds=2.0)
    config = opa_eval.OpaConfig(
        rego_dir=stub.parent,
        opa_bin=str(stub),
        timeout_seconds=0.1,
    )
    with pytest.raises(opa_eval.OpaUnavailableError, match="timed out"):
        opa_eval.evaluate_entrypoint(
            config,
            "defenseclaw.admission.verdict",
            input_payload={},
            data_payload={},
        )


def test_evaluate_entrypoint_raises_on_unparseable_json(opa_stub) -> None:
    stub = opa_stub(stdout_override="not-json")
    config = _config_for(stub)
    with pytest.raises(opa_eval.OpaUnavailableError, match="unparseable JSON"):
        opa_eval.evaluate_entrypoint(
            config,
            "defenseclaw.admission.verdict",
            input_payload={},
            data_payload={},
        )


def test_evaluate_entrypoint_writes_input_and_data_files(opa_stub, tmp_path: Path) -> None:
    """We can't easily inspect the temp dir after the wrapper
    cleans it up; instead we use the workspace= override to keep
    the files around and assert their contents.
    """
    stub = opa_stub(verdict_value=42)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    config = _config_for(stub)
    opa_eval.evaluate_entrypoint(
        config,
        "defenseclaw.x.verdict",
        input_payload={"a": 1},
        data_payload={"b": 2},
        workspace=workspace,
    )
    assert json.loads((workspace / "input.json").read_text()) == {"a": 1}
    assert json.loads((workspace / "data.json").read_text()) == {"b": 2}


# --- evaluate_domain -----------------------------------------------------


def test_evaluate_domain_returns_verdict_and_reason(opa_stub) -> None:
    stub = opa_stub(verdict_value="blocked", reason_value="rule SEC-AWS-KEY")
    config = _config_for(stub)
    result = opa_eval.evaluate_domain(
        config,
        "admission",
        input_payload={"hook": "x"},
        data_payload={},
    )
    assert result.verdict == "blocked"
    assert result.reason == "rule SEC-AWS-KEY"
    assert result.raw == {"verdict": "blocked", "reason": "rule SEC-AWS-KEY"}


def test_evaluate_domain_skips_reason_when_domain_has_none(opa_stub) -> None:
    """``skill_actions`` has no reason entrypoint, so we shouldn't
    invoke ``opa eval`` twice."""
    stub = opa_stub(verdict_value="block")
    config = _config_for(stub)
    result = opa_eval.evaluate_domain(
        config,
        "skill_actions",
        input_payload={},
        data_payload={},
    )
    assert result.verdict == "block"
    assert result.reason == ""


def test_evaluate_domain_returns_undefined_label_when_verdict_missing(
    opa_stub,
) -> None:
    empty_payload = json.dumps({"result": []})
    stub = opa_stub(stdout_override=empty_payload)
    config = _config_for(stub)
    result = opa_eval.evaluate_domain(
        config,
        "admission",
        input_payload={},
        data_payload={},
    )
    assert result.verdict == "(undefined)"


# --- verdict_tone --------------------------------------------------------


def test_verdict_tone_buckets_known_labels() -> None:
    for label in ("allowed", "allow", "clean", "true"):
        assert opa_eval.verdict_tone(label) == "positive"
    for label in ("warning", "alert", "scan"):
        assert opa_eval.verdict_tone(label) == "caution"
    for label in ("blocked", "rejected", "block", "deny", "false"):
        assert opa_eval.verdict_tone(label) == "negative"
    for label in ("(undefined)", "", "anything-else"):
        assert opa_eval.verdict_tone(label) == "neutral"
