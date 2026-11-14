# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor and status rows for route-only mode (S1 1.0.10 items 3 and 4)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import doctor_route_only as dro
from defenseclaw import routing_route_only as ro

_ANTHROPIC = {"base_url": "https://api.anthropic.com", "api": "messages"}
_BEDROCK_PROFILE = {
    "base_url": "https://bedrock-runtime.us-west-2.amazonaws.com",
    "api": "invoke",
    "bedrock": {"auth": "profile", "profile": "bedrock-dev", "region": "us-west-2"},
}


def _cfg(tmp_path: Path, upstreams: dict, *, enabled: bool = True, models: list | None = None) -> SimpleNamespace:
    routing = SimpleNamespace(
        enabled=enabled, models=models or [], route_only={"connectors": list(upstreams), "upstreams": upstreams}
    )
    return SimpleNamespace(
        routing=routing, gateway=SimpleNamespace(api_port=18970), data_dir=str(tmp_path), deployment_mode=""
    )


def _health(*rows: dict) -> dict:
    return {"routing": {"state": "running", "details": {"enabled": True, "route_only": list(rows)}}}


@pytest.fixture(autouse=True)
def homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("claude", "codex"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    for k in list(os.environ):
        if k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_")):
            monkeypatch.delenv(k, raising=False)
    return tmp_path


def _by_label(rows: list[dro.Row]) -> dict[str, dro.Row]:
    return {row.label: row for row in rows}


def _render_claude(tmp_path: Path, base: str = "http://127.0.0.1:18970/r/claudecode") -> None:
    env = {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_CUSTOM_HEADERS": "X-DC-Route-Auth: dcr1-abc"}
    (tmp_path / "claude" / "settings.json").write_text(json.dumps({"env": env}), encoding="utf-8")


def test_nothing_routed_and_routing_off(tmp_path: Path) -> None:
    assert dro.route_only_rows(_cfg(tmp_path, {}), None) == []
    rows = dro.route_only_rows(_cfg(tmp_path, {"claudecode": _ANTHROPIC}, enabled=False), None)
    assert [r.tag for r in rows] == ["warn"] and "routing.enabled is false" in rows[0].detail


def test_ready_passthrough_and_agent_config(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    live = _health(
        {
            "connector": "claudecode",
            "mounted": True,
            "ready": True,
            "credential": "agent",
            "provider": "anthropic",
            "upstream": "https://api.anthropic.com",
        }
    )
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    assert rows["Route-only claudecode"].tag == "pass"
    assert "agent credential is passed through" in rows["Route-only claudecode"].detail
    assert rows["Route-only claudecode agent config"].tag == "warn"
    _render_claude(tmp_path)
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    assert rows["Route-only claudecode agent config"].tag == "pass"
    _render_claude(tmp_path, "https://api.anthropic.com")
    drift = _by_label(dro.route_only_rows(cfg, live, platform="linux"))["Route-only claudecode agent config"]
    assert drift.tag == "warn" and "defenseclaw-gateway restart" in drift.fix


def test_codex_agent_config(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"codex": {"base_url": "https://api.openai.com/v1", "api": "responses"}})
    (tmp_path / "codex" / "config.toml").write_text(
        'model_provider = "defenseclaw_route"\n\n[model_providers.defenseclaw_route]\n'
        'base_url = "http://127.0.0.1:18970/r/codex"\n',
        encoding="utf-8",
    )
    rows = _by_label(dro.route_only_rows(cfg, _health(), platform="linux"))
    assert rows["Route-only codex agent config"].tag == "pass"
    assert rows["Route-only codex"].tag == "warn"  # an older gateway reports no state


def test_custody_without_a_gateway_key_fails(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    fix = "set routing.models[].credential for anthropic (base_url https://api.anthropic.com) in the policy bundle"
    live = _health(
        {
            "connector": "claudecode",
            "mounted": True,
            "custody": True,
            "ready": False,
            "credential": "missing",
            "problem": "every model call answers 503",
            "fix": fix,
        }
    )
    row = _by_label(dro.route_only_rows(cfg, live, profile="standalone", platform="darwin"))["Route-only claudecode"]
    assert row.tag == "fail" and row.fix == fix
    # Gateway down: the same gap is found offline from config.yaml.
    row = dro.route_only_rows(cfg, None, profile="standalone", platform="darwin")[0]
    assert row.tag == "fail" and row.fix == fix
    covered = _cfg(
        tmp_path, {"claudecode": _ANTHROPIC}, models=[{"name": "s", "provider": "anthropic", "credential": "org"}]
    )
    row = dro.route_only_rows(covered, None, profile="standalone", platform="darwin")[0]
    assert row.tag == "fail" and "guardian" in row.fix
    assert dro.route_only_rows(cfg, None, profile="standalone", platform="linux")[0].fix.startswith("the guardian")
    assert not dro.custody_covered(
        _cfg(tmp_path, {}, models=[{"provider": "anthropic", "credential": "org", "base_url": "https://llm.corp"}]),
        _ANTHROPIC,
    )
    assert dro.custody_covered(
        cfg,
        {
            "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
            "api": "invoke",
            "bedrock": {"auth": "instance_role"},
        },
    )


def test_gateway_down_names_the_way_back(tmp_path: Path) -> None:
    # Commands that exist in this tree (REVIEW-code-doctor P2-1).
    row = dro.route_only_rows(_cfg(tmp_path, {"claudecode": _ANTHROPIC}), None, platform="linux")[0]
    assert row.tag == "fail" and "defenseclaw-gateway start" in row.fix
    assert "remove claudecode from routing.route_only.connectors in config.yaml" in row.fix
    assert "defenseclaw-gateway connector route-restore --connector claudecode" in row.fix
    row = dro.route_only_rows(_cfg(tmp_path, {"claudecode": {}}), None, platform="linux")[0]
    assert row.tag == "fail"
    assert row.fix == "set routing.route_only.upstreams.claudecode (base_url and api) in config.yaml"
    for rows in (
        dro.route_only_rows(_cfg(tmp_path, {"claudecode": _ANTHROPIC}), None, platform="linux"),
        dro.route_only_rows(_cfg(tmp_path, {"claudecode": _ANTHROPIC}, enabled=False), None),
        [dro.shared_mac_row(["claudecode"], ["alice", "bob"])],
    ):
        assert not any("defenseclaw routing " in row.fix for row in rows)


def test_gateway_states_without_live_readiness(tmp_path: Path) -> None:
    """Foreground, foreign holder and unverified listener (REVIEW-code-doctor P2-2)."""
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    _render_claude(tmp_path)
    ready = _health({"connector": "claudecode", "ready": True, "credential": "agent"})
    fg = _by_label(dro.route_only_rows(cfg, None, platform="linux", gateway=dro.GATEWAY_FOREGROUND))
    assert fg["Route-only claudecode"].tag == "skip" and "foreground" in fg["Route-only claudecode"].detail
    assert fg["Route-only claudecode agent config"].tag == "pass"  # the offline checks still run
    foreign = dro.route_only_rows(
        cfg,
        None,
        platform="linux",
        gateway=dro.GATEWAY_FOREIGN,
        holder="another account (uid 4242)",
        holder_fix="That process belongs to another account, so move this account's gateway",
    )[0]
    assert foreign.tag == "fail" and "held by another account (uid 4242)" in foreign.detail
    assert "not running" not in foreign.detail and foreign.fix.startswith("That process belongs")
    assert "route-restore --connector claudecode" in foreign.fix
    # An unverified listener: its /health is not trusted, even when it says ready.
    unverified = dro.route_only_rows(cfg, ready, platform="linux", gateway=dro.GATEWAY_UNVERIFIED)[0]
    assert unverified.tag == "skip" and "not verified" in unverified.detail
    assert dro.route_only_rows(cfg, ready, platform="linux")[0].tag == "pass"


def test_doctor_passes_the_gateway_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.commands import cmd_doctor, cmd_status

    monkeypatch.setattr(cmd_status, "_enterprise_profile", lambda cfg: "")
    monkeypatch.setattr(cmd_doctor, "_foreign_gateway_port_remediation", lambda cfg, then="start", holder="": "move it")
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    ready = _health({"connector": "claudecode", "ready": True, "credential": "agent"})
    for down, unverified, health, tag, text in (
        ("foreground", True, None, "skip", "foreground"),
        ("foreign", False, None, "fail", "held by another account (uid 7)"),
        ("", True, ready, "skip", "not verified"),
        ("stopped", False, None, "fail", "not running"),
        ("", False, ready, "pass", "anthropic"),
    ):
        r = cmd_doctor._DoctorResult(quiet=True)
        r.gateway_down, r.sidecar_unverified, r.gateway_holder = down, unverified, "another account (uid 7)"
        cmd_doctor._check_route_only(cfg, r, live_health=health)
        row = next(c for c in r.checks if c["label"] == "Route-only claudecode")
        assert row["status"] == tag and text in row["detail"], (down, row)


def test_bedrock_signing_rows_from_the_gateway(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _BEDROCK_PROFILE})
    good = {
        "auth": "profile",
        "profile": "bedrock-dev",
        "profile_found": True,
        "region": "us-west-2",
        "region_ok": True,
        "signer": True,
        "credential": True,
    }
    live = _health(
        {"connector": "claudecode", "mounted": True, "ready": True, "credential": "gateway_signing", "signing": good}
    )
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    for name in ("signer", "region", "profile", "credential"):
        assert rows[f"Route-only claudecode Bedrock {name}"].tag == "pass", name
    bad = {
        "auth": "profile",
        "profile": "bedrock-dev",
        "profile_found": True,
        "region": "us-west-2",
        "region_ok": True,
        "signer": True,
        "credential": False,
        "credential_error": "the SSO session has expired",
    }
    live = _health(
        {
            "connector": "claudecode",
            "mounted": True,
            "ready": False,
            "credential": "gateway_signing",
            "signing": bad,
            "problem": "gateway Bedrock signing is not ready",
            "fix": "check it",
        }
    )
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    assert rows["Route-only claudecode"].tag == "fail"
    cred = rows["Route-only claudecode Bedrock credential"]
    assert cred.tag == "fail" and "SSO session" in cred.detail and "aws sso login" in cred.fix
    missing = dict(bad, signer=False, profile_found=False, signer_error="profile gone")
    rows = _by_label(
        dro.route_only_rows(
            cfg, _health({"connector": "claudecode", "ready": False, "signing": missing}), platform="linux"
        )
    )
    assert rows["Route-only claudecode Bedrock profile"].tag == "fail"
    assert "Route-only claudecode Bedrock credential" not in rows  # no signer, nothing fetched
    # The region failed: the gateway never tried the signer, so no signer row.
    no_region = {"auth": "profile", "region_ok": False, "region_error": "no region", "signer": False}
    rows = _by_label(
        dro.route_only_rows(
            cfg, _health({"connector": "claudecode", "ready": False, "signing": no_region}), platform="linux"
        )
    )
    assert rows["Route-only claudecode Bedrock region"].tag == "fail"
    assert "Route-only claudecode Bedrock signer" not in rows


def test_bedrock_signing_rows_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    aws = tmp_path / "aws"
    aws.mkdir()
    (aws / "config").write_text("[profile bedrock-dev]\nregion = us-west-2\n", encoding="utf-8")
    (aws / "credentials").write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(aws / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(aws / "credentials"))
    rows = _by_label(dro.route_only_rows(_cfg(tmp_path, {"claudecode": _BEDROCK_PROFILE}), None, platform="linux"))
    assert rows["Route-only claudecode Bedrock region"].tag == "pass"
    assert rows["Route-only claudecode Bedrock profile"].tag == "pass"
    assert rows["Route-only claudecode Bedrock credential"].tag == "skip"
    other = dict(_BEDROCK_PROFILE, bedrock={"auth": "profile", "profile": "gone", "region": "eu-west-1"})
    rows = _by_label(dro.route_only_rows(_cfg(tmp_path, {"claudecode": other}), None, platform="linux"))
    assert rows["Route-only claudecode Bedrock region"].tag == "fail"
    assert "us-west-2" in rows["Route-only claudecode Bedrock region"].detail
    assert rows["Route-only claudecode Bedrock profile"].tag == "fail"
    passthrough = dict(_BEDROCK_PROFILE, bedrock={"auth": "passthrough"})
    assert not dro.signing_rows("claudecode", passthrough, None)
    padded = dict(_BEDROCK_PROFILE, bedrock={"auth": "profile", "profile": "bedrock-dev", "region": " us-west-2 "})
    assert _by_label(dro.signing_rows("claudecode", padded, None))["Route-only claudecode Bedrock region"].tag == "pass"
    corp = dict(_BEDROCK_PROFILE, base_url="https://llm.example.corp/bedrock?token=abc")
    signer = _by_label(dro.signing_rows("claudecode", corp, None))["Route-only claudecode Bedrock signer"]
    assert signer.tag == "fail" and "https://llm.example.corp" in signer.detail and "token" not in signer.detail


def test_held_api_port_and_shared_mac(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    (tmp_path / "hooks").mkdir()
    mark = tmp_path / "hooks" / dro.PORT_HELD_MARK
    mark.write_text(json.dumps({"uid": 4242}), encoding="utf-8")
    rows = _by_label(dro.route_only_rows(cfg, None, platform="linux"))
    held = rows["Route-only API port"]
    assert held.tag == "fail" and "uid 4242" in held.detail and 'sudo ss -ltnp "sport = :18970"' in held.fix
    # Windows names the SID when the gateway could read the holder token, else no account.
    mark.write_text(json.dumps({"addr": "127.0.0.1:18970"}), encoding="utf-8")
    held = _by_label(dro.route_only_rows(cfg, None, platform="win32"))["Route-only API port"]
    assert "another account held" in held.detail and "uid" not in held.detail and "Get-NetTCPConnection" in held.fix
    mark.write_text(json.dumps({"addr": "127.0.0.1:18970", "sid": "S-1-5-21-1-2-3-1001"}), encoding="utf-8")
    held = _by_label(dro.route_only_rows(cfg, None, platform="win32"))["Route-only API port"]
    assert "another account (S-1-5-21-1-2-3-1001) held" in held.detail
    rows = _by_label(dro.route_only_rows(cfg, None, platform="darwin", accounts=["alice"]))
    assert "Route-only on a shared Mac" not in rows
    rows = _by_label(dro.route_only_rows(cfg, None, platform="darwin", accounts=["alice", "bob"]))
    assert rows["Route-only on a shared Mac"].tag == "warn"
    assert "Route-only on a shared Mac" not in _by_label(
        dro.route_only_rows(cfg, None, platform="linux", accounts=["alice", "bob"])
    )
    assert "Route-only on a shared Mac" not in _by_label(
        dro.route_only_rows(cfg, None, profile="standalone", platform="darwin", accounts=["alice", "bob"])
    )


def test_mac_accounts_counts_real_users(monkeypatch: pytest.MonkeyPatch) -> None:
    out = "_spotlight 89\nnobody -2\nroot 0\nalice 501\nbob 502\ndaemon 1\n"
    monkeypatch.setattr(dro.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=out, stderr=""))
    assert dro.mac_accounts() == ["alice", "bob"]

    def broken(*_a, **_k):
        raise OSError("no dscl")

    monkeypatch.setattr(dro.subprocess, "run", broken)
    assert dro.mac_accounts() is None and dro.shared_mac_row(["claudecode"]) is None


def test_broken_agent_file_keeps_the_other_rows(tmp_path: Path) -> None:
    """An unparsable config.toml warns for codex only (REVIEW-code-doctor P3-3)."""
    codex = {"base_url": "https://api.openai.com/v1", "api": "responses"}
    cfg = _cfg(tmp_path, {"codex": codex, "claudecode": _ANTHROPIC})
    (tmp_path / "codex" / "config.toml").write_text("model_provider = [broken\n", encoding="utf-8")
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / dro.PORT_HELD_MARK).write_text(json.dumps({"uid": 4242}), encoding="utf-8")
    rows = _by_label(dro.route_only_rows(cfg, None, platform="linux"))
    assert rows["Route-only codex agent config"].tag == "warn"
    assert "could not read the codex agent config" in rows["Route-only codex agent config"].detail
    assert rows["Route-only claudecode"].tag == "fail" and rows["Route-only API port"].tag == "fail"


def test_agent_config_drift_names_why_nothing_rendered(tmp_path: Path) -> None:
    """No render for a connector that is not set up, or while signing fails (P3-4)."""
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    cfg.active_connectors = lambda: ["codex"]
    drift = _by_label(dro.route_only_rows(cfg, None, platform="linux"))["Route-only claudecode agent config"]
    assert drift.tag == "warn" and "defenseclaw setup claude-code" in drift.fix and "restart" not in drift.fix
    cfg = _cfg(tmp_path, {"claudecode": dict(_BEDROCK_PROFILE, bedrock={"auth": "instance_role"})})
    cfg.active_connectors = lambda: ["claudecode"]
    no_region = {"auth": "instance_role", "region_ok": False, "region_error": "no region"}
    live = _health({"connector": "claudecode", "ready": False, "signing": no_region})
    drift = _by_label(dro.route_only_rows(cfg, live, platform="linux"))["Route-only claudecode agent config"]
    assert "fix the failing Route-only claudecode Bedrock rows" in drift.fix
    # Secure Client: the gateway renders nothing, so no agent config row.
    rows = _by_label(dro.route_only_rows(cfg, live, profile="secure_client", platform="darwin", accounts=[]))
    assert "Route-only claudecode agent config" not in rows


def test_routing_off_on_a_managed_host_names_the_bundle(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC}, enabled=False)
    row = dro.route_only_rows(cfg, None, profile="standalone")[0]
    assert row.fix == "the policy bundle lists route-only connectors with routing off; update the bundle"
    assert "routing.enabled in config.yaml" in dro.route_only_rows(cfg, None)[0].fix


def test_agent_config_shows_only_the_origin_of_a_foreign_url(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    _render_claude(tmp_path, "https://llm.corp.example/v1?key=secret")
    drift = _by_label(dro.route_only_rows(cfg, None, platform="linux"))["Route-only claudecode agent config"]
    assert "https://llm.corp.example," in drift.detail and "secret" not in drift.detail


def test_status_keeps_one_state_per_connector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.commands import cmd_status

    monkeypatch.setattr(cmd_status, "_enterprise_profile", lambda cfg: "")
    cfg = _cfg(tmp_path, {"claudecode": _BEDROCK_PROFILE})
    rows = cmd_status._route_only_status(cfg, None)
    assert [r["label"] for r in rows] == ["Route-only claudecode"] and rows[0]["tag"] == "fail"


def test_enable_on_a_managed_host_names_the_bundle_and_custody_key(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {})
    cfg.deployment_mode = "managed_enterprise"
    with pytest.raises(ro.RouteOnlyError, match=r"policy bundle .*routing\.models\[\]\.credential"):
        ro.enable(cfg, "claudecode")
