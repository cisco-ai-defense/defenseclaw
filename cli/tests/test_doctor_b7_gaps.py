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


def test_llm_reachable_names_the_shell_proxy(tmp_path, monkeypatch) -> None:
    # GAP-2421: a dead HTTPS_PROXY read as a bare "[Errno 61] Connection refused".
    import requests

    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "DEFENSECLAW_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    cfg = _bedrock_judge_cfg(tmp_path, "api_key")
    refused = requests.ConnectionError("[Errno 61] Connection refused")
    monkeypatch.setenv("HTTPS_PROXY", "http://u:pw@127.0.0.1:18508")
    r = _DoctorResult()
    with mock.patch("litellm.completion", side_effect=refused):
        cmd_doctor._check_llm_reachable(cfg, r)
    row = r.checks[-1]
    assert row["status"] == "warn"
    assert "could not be reached through the proxy http://127.0.0.1:18508 (from HTTPS_PROXY)" in row["detail"]
    assert "pw" not in row["detail"] and "unset HTTPS_PROXY" in row["remediation"]
    # NO_PROXY covering the provider host: the call goes direct, no proxy wording.
    monkeypatch.setenv("NO_PROXY", ".amazonaws.com")
    r = _DoctorResult()
    with mock.patch("litellm.completion", side_effect=refused):
        cmd_doctor._check_llm_reachable(cfg, r)
    assert "proxy" not in r.checks[-1]["detail"] and not r.checks[-1].get("remediation")


def test_llm_reachable_proxy_names_lowercase_var_and_plain_timeout(tmp_path, monkeypatch) -> None:
    # GAP-2446: a lowercase https_proxy was reported (and "unset") as HTTPS_PROXY.
    # GAP-2447: a proxy timeout ended with "litellm.Timeout: ... after None seconds".
    import os

    import litellm
    import requests

    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "DEFENSECLAW_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    var = "HTTPS_PROXY" if os.name == "nt" else "https_proxy"  # Windows env names ignore case
    cfg = _bedrock_judge_cfg(tmp_path, "api_key")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:18508")
    r = _DoctorResult()
    with mock.patch("litellm.completion", side_effect=requests.ConnectionError("[Errno 61] Connection refused")):
        cmd_doctor._check_llm_reachable(cfg, r)
    row = r.checks[-1]
    assert f"(from {var})" in row["detail"] and f"unset {var}" in row["remediation"]
    timeout = litellm.Timeout(message="Connection timed out after None seconds.", model="m", llm_provider="bedrock")
    r = _DoctorResult()
    with mock.patch("litellm.completion", side_effect=timeout):
        cmd_doctor._check_llm_reachable(cfg, r)
    detail = r.checks[-1]["detail"]
    assert f"Bedrock timed out after 5 s through the proxy http://127.0.0.1:18508 (from {var})" in detail
    assert "litellm" not in detail and "None seconds" not in detail
