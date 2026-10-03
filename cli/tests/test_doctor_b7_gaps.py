"""doctor regressions: idle sandbox instances fold, rejected Bedrock judge key FAILs."""

from __future__ import annotations

from unittest import mock

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.observability.custody_status import ConnectorCustodyReport, ConnectorCustodyStatus

from tests.test_doctor_next_steps import _bedrock_judge_cfg


def _instance(n: int, *, default: bool = False, custody: str = "external", **kw) -> ConnectorCustodyStatus:
    return ConnectorCustodyStatus(
        connector_instance_id=f"019b0000-0000-7000-8000-{n:012d}",
        connector="claudecode",
        custody=custody,
        profile_version="claudecode-v1",
        default=default,
        **kw,
    )


def test_idle_additional_instances_fold_into_one_pass_row() -> None:
    # GAP-2104: one WARN row per past sandbox run with migration advice.
    instances = [_instance(0, default=True, custody="defenseclaw", managed_config_state="verified", normalized_batches=4)]
    instances += [_instance(n) for n in range(1, 8)]
    instances += [_instance(n, custody="defenseclaw", managed_config_state="verified") for n in range(8, 12)]
    instances += [_instance(n, custody="hook_only") for n in range(12, 14)]
    instances.append(_instance(14, credential_state="invalid", authentication_failures=2))
    report = ConnectorCustodyReport(state="available", reason="", observation_window_hours=24, instances=tuple(instances))
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    rows = [c for c in r.checks if c["label"].startswith("Connector OTLP")]
    # 13 idle additional instances (external, defenseclaw and hook-only custody).
    folded = [c for c in rows if c["label"] == "Connector OTLP: claudecode (13 additional instances)"]
    assert len(folded) == 1 and folded[0]["status"] == "pass"
    assert "nothing to do" in folded[0]["detail"]
    # Only the default row, the folded row and the instance with failures remain.
    assert len(rows) == 3
    assert [c["status"] for c in rows if "/" in c["label"]] == ["fail"]
    assert not any("managed connector setup" in c["detail"] for c in rows if c["status"] != "fail")


@mock.patch(
    "defenseclaw.commands.cmd_doctor._http_probe",
    return_value=(403, '{"Message":"Authentication failed: Please make sure your API Key is valid."}'),
)
def test_rejected_bedrock_key_is_fail_with_replace_step(_probe) -> None:
    # GAP-2108: an expired key read as "lacks ListFoundationModels".
    r = _DoctorResult()
    cmd_doctor._verify_bedrock("bedrock-api-key-" + "A" * 40, r, key_env="DEFENSECLAW_LLM_KEY")
    row = r.checks[-1]
    assert row["status"] == "fail" and "expired or invalid" in row["detail"]
    assert "Authentication failed" in row["detail"] and "ListFoundationModels" not in row["detail"]
    assert "defenseclaw keys set DEFENSECLAW_LLM_KEY --value-stdin" in row["remediation"]


@mock.patch(
    "defenseclaw.commands.cmd_doctor._http_probe",
    return_value=(403, '{"Message":"User: arn:aws:iam::1:user/x is not authorized to perform: bedrock:ListFoundationModels"}'),
)
def test_bedrock_iam_denial_stays_warn(_probe) -> None:
    r = _DoctorResult()
    cmd_doctor._verify_bedrock("ABSKscoped==", r)
    assert r.checks[-1]["status"] == "warn" and "InvokeModel may still work" in r.checks[-1]["detail"]


def test_judge_auth_failure_fails_llm_reachable(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_LLM_MODEL", raising=False)
    cfg = _bedrock_judge_cfg(tmp_path, "api_key")
    msg = "Bedrock authentication failed: Authentication failed: Please make sure your API Key is valid."
    r = _DoctorResult()
    with mock.patch("defenseclaw.llm.ping", return_value=(False, msg)):
        cmd_doctor._check_llm_reachable(cfg, r)
    row = r.checks[-1]
    assert row["status"] == "fail" and "fail open" in row["detail"]
    assert "keys set DEFENSECLAW_LLM_KEY --value-stdin" in row["remediation"]
    r = _DoctorResult()
    with mock.patch("defenseclaw.llm.ping", return_value=(False, "Bedrock timed out: read timeout")):
        cmd_doctor._check_llm_reachable(cfg, r)
    assert r.checks[-1]["status"] == "warn"


def test_bedrock_key_rejection_raised_as_connection_error_is_auth_failed() -> None:
    # GAP-2108: LiteLLM raises a Bedrock 403 for an expired or malformed key as
    # APIConnectionError (status 500) whose text has no 403.
    from defenseclaw import llm

    err = type("APIConnectionError", (Exception,), {})
    for body in ("Bearer Token has expired", "Invalid API Key format: Delimiter ':' not found"):
        exc = err(f'litellm.APIConnectionError: BedrockException - {{"Message":"{body}"}}')
        assert llm._classify_llm_exception(exc) == "auth_failed"
    assert llm._classify_llm_exception(err("litellm.APIConnectionError: Connection refused")) == "network_error"
